from time import time

def job_tracker(func):
        fxn = func.__name__
        def wrapper(*args, **kwargs):
            class_instance = args[0]
            running,finished,timing = init_job_tracker(class_instance)
            running[fxn] += 1
            start = time()
            result = func(*args, **kwargs)
            elapsed = time() - start
            running[fxn] -= 1
            finished[fxn] += 1
            timing[fxn] = round(((finished[fxn]-1 * timing[fxn] ) + elapsed ) / finished[fxn], 4)
            if running[fxn] == 0: running.pop(fxn)
            return result
        
        def init_job_tracker(class_instance):
            if not class_instance.job_stats:
                class_instance.job_stats = {'running': {}, 'finished': {}, 'timing': {}}
            running  = class_instance.job_stats.get('running', {})
            finished = class_instance.job_stats.get('finished', {})
            timing   = class_instance.job_stats.get('timing', {})

            running[fxn] = running.get(fxn, 0)
            finished[fxn] = finished.get(fxn, 0)
            timing[fxn] = timing.get(fxn, 0)

            return running, finished, timing
            
             
            
        return wrapper