from cxconfig import CXCONFIG
from cxfuncs import CXFUZZ
import argparse
import os
import random
import sys
import time
import torch
import xxhash

def main():
    print("\n+++++cxfuzz start+++++\n")

    # cxfuzz instance
    cxfuzz = CXFUZZ()

    # register signal
    cxfuzz.register_signal_handlers()

    # init some thing
    '''
    count_class_lookup8,fuzzing_api_nums,map_size,full_map_size,trace_bits,virgin_bits,crash_bits
    interesting_float_values,interesting_int_values,interesting_uint_values,api_queue_nums,api_crash_nums
    '''
    cxfuzz.init_some_thing()

    # check core pattern
    cxfuzz.check_core_pattern()

    # parse args
    parser = argparse.ArgumentParser()
    parser.add_argument('--o',type=str,required=True,help='output directory path')
    parser.add_argument('--a',type=str,help='api to test')
    args = parser.parse_args()
    cxfuzz.output_dir = os.path.join(args.o, 'default')
    cxfuzz.debug_api = args.a

    # create output folder
    cxfuzz.create_output_folder()

    # load pt apis
    total_apis_list = []
    api_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pytorch_apis.txt')
    exclude_api_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pytorch_exclude_apis.txt')
    try:
        with open(api_file_path, 'r') as include_file:
            api_list = [line.strip() for line in include_file if line.strip()]
        with open(exclude_api_file_path, 'r') as exclude_file:
            exclude_api_list = {line.strip() for line in exclude_file if line.strip()}
        total_apis_list = [api for api in api_list if api not in exclude_api_list]
    except:
        cxfuzz.fatal_error("load apis failed")
    if cxfuzz.debug_api:
        total_apis_list = [cxfuzz.debug_api]
    if len(total_apis_list) <= cxfuzz.fuzzing_api_nums:
        cxfuzz.fuzzing_api_list = total_apis_list.copy()
    else:
        cxfuzz.fuzzing_api_list = random.sample(total_apis_list,cxfuzz.fuzzing_api_nums)

    # create api folders
    cxfuzz.create_api_folders()

    # create api files
    cxfuzz.create_api_files()

    # init kewards, keyward_values
    cxfuzz.init_kewards_and_values()

    # add kewards to interesting strings
    cxfuzz.interesting_strings += cxfuzz.interesting_kewards

    # init api_queue_nums api_crash_nums api_queue_list
    cxfuzz.api_queue_nums = {api_name: 0 for api_name in cxfuzz.fuzzing_api_list}
    cxfuzz.api_crash_nums = {api_name: 0 for api_name in cxfuzz.fuzzing_api_list}
    cxfuzz.api_queue_list = {api_name: [] for api_name in cxfuzz.fuzzing_api_list}

    # create empty queue
    cxfuzz.create_empty_queue()

    # select api to fuzz
    selected = random.choice(cxfuzz.fuzzing_api_list)
    cxfuzz.set_cur_api_to_fuzz(selected)

    # choose one seed from queue to input_for_mutate
    cxfuzz.choose_one_seed()

    # test start
    # cxfuzz.test()
    # test end

    # fuzz loop
    while not cxfuzz.stop_requested:
        cxfuzz.iterations += 1
        if cxfuzz.iterations % cxfuzz.shm_clean_threshold == 0:
            cxfuzz.cleanup_unused_shm_files()
        if cxfuzz.iterations % cxfuzz.api_switch_threshold == 0:
            cxfuzz.save_cur_api_fuzz_info()
            selected = random.choice(cxfuzz.fuzzing_api_list)
            cxfuzz.set_cur_api_to_fuzz(selected)
            cxfuzz.cur_map_density = cxfuzz.virgin_byte_density()
        cxfuzz.choose_one_seed()
        cxfuzz.stage_cur = 0
        cxfuzz.stage_max = 16
        cxfuzz.update_queue_fuzzed()
        while cxfuzz.stage_cur < cxfuzz.stage_max and not cxfuzz.stop_requested:
            cxfuzz.stage_cur = cxfuzz.stage_cur + 1
            cxfuzz.cur_output_args_of_mutate = cxfuzz.cur_input_args_for_mutate.copy()
            cxfuzz.cur_output_kwargs_of_mutate = cxfuzz.cur_input_kwargs_for_mutate.copy()
            if cxfuzz.cur_api_is_class:
                cxfuzz.cur_output_args_of_mutate2 = cxfuzz.cur_input_args_for_mutate2.copy()
                cxfuzz.cur_output_kwargs_of_mutate2 = cxfuzz.cur_input_kwargs_for_mutate2.copy()
            cxfuzz.mutate()
            if cxfuzz.cur_api_is_class:
                cxfuzz.cur_output_args_of_mutate3 = cxfuzz.cur_output_args_of_mutate.copy()
                cxfuzz.cur_output_kwargs_of_mutate3 = cxfuzz.cur_output_kwargs_of_mutate.copy()
                cxfuzz.cur_output_args_of_mutate = cxfuzz.cur_output_args_of_mutate2.copy()
                cxfuzz.cur_output_kwargs_of_mutate = cxfuzz.cur_output_kwargs_of_mutate2.copy()
                cxfuzz.mutate()
                cxfuzz.cur_output_args_of_mutate2 = cxfuzz.cur_output_args_of_mutate.copy()
                cxfuzz.cur_output_kwargs_of_mutate2 = cxfuzz.cur_output_kwargs_of_mutate.copy()
                cxfuzz.cur_output_args_of_mutate = cxfuzz.cur_output_args_of_mutate3.copy()
                cxfuzz.cur_output_kwargs_of_mutate = cxfuzz.cur_output_kwargs_of_mutate3.copy()
                cxfuzz.cur_output_args_of_mutate3 = []
                cxfuzz.cur_output_kwargs_of_mutate3 = {}
            status = cxfuzz.runapi()
            cxfuzz.classify_counts()
            if status < 0:
                # crash
                cxfuzz.total_crashes +=1
                hnc = cxfuzz.has_new_crash()
                if hnc > 0:
                    cxfuzz.save_to_crash()
                    cxfuzz.update_crash_bits()
                    cxfuzz.hnc_nums += 1
            else:
                # no crash
                if status == 1:
                    # timeout
                    cxfuzz.timeout_nums +=1
                elif status == 2:
                    # memout
                    cxfuzz.memout_nums +=1
                elif status == 0:
                    hnb = cxfuzz.has_new_bits()
                    if hnb > 0:
                        if cxfuzz.stage_max < 256:
                            cxfuzz.stage_max = cxfuzz.stage_max * 2
                        cxfuzz.save_to_queue()
                        cxfuzz.update_virgin_bits()
                        cxfuzz.update_queue_minibits_dict()
                        cxfuzz.update_favored_queue()
                        cxfuzz.cur_map_density = cxfuzz.virgin_byte_density()
                    cur_hash = xxhash.xxh32(cxfuzz.trace_bits.tobytes()).intdigest()
                    if cur_hash not in cxfuzz.queue_hashes:
                        cxfuzz.queue_hashes.add(cur_hash)
                        # run asan in cpu/gpu and (todo:differential testing)
                        if cxfuzz.enable_asan_check == True:
                            cxfuzz.save_to_cur_input()
                            crashed = cxfuzz.run_with_asan()
                            if crashed:
                                cxfuzz.total_crashes +=1
                                cxfuzz.asan_crashes +=1
                                cxfuzz.save_to_crash()
                        elif cxfuzz.enable_asan_check == False:
                            pass
                        else:
                            cxfuzz.fatal_error()
                        if cxfuzz.enable_diff_check == True:
                            # cxfuzz.save_to_cur_input()
                            # may_bugs = cxfuzz.run_with_diff_check()
                            pass
                        elif cxfuzz.enable_diff_check == False:
                            pass
                        else:
                            cxfuzz.fatal_error()
                else:
                    cxfuzz.fatal_error(f"status:{status}")
            cxfuzz.show_stats()

    # exit
    cxfuzz.exit_fuzz()

    print("\n+++++cxfuzz end+++++\n")

if __name__ == '__main__':
    main()
