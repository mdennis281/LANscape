def job_tracker(func):
        fxn = func.__name__
        def wrapper(*args, **kwargs):
            class_instance = args[0]
            running,finished = init_job_tracker(class_instance)
            running[fxn] += 1
            result = func(*args, **kwargs)
            running[fxn] -= 1
            finished[fxn] += 1
            return result
        
        def init_job_tracker(class_instance):
            if not class_instance.job_stats:
                class_instance.job_stats = {'running': {}, 'finished': {}}
            running = class_instance.job_stats.get('running', {})
            finished = class_instance.job_stats.get('finished', {})

            running[fxn] = running.get(fxn, 0)
            finished[fxn] = finished.get(fxn, 0)

            return running, finished
            
             
            
        return wrapper