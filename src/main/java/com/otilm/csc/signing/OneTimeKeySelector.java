package com.otilm.csc.signing;

import com.otilm.csc.service.keys.KeysService;
import com.otilm.csc.service.keys.OneTimeKey;
import com.otilm.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

@Component
public class OneTimeKeySelector extends LocalKeySelector<OneTimeKey> {


    public OneTimeKeySelector(KeysService<OneTimeKey> keysService,
                              WorkerRepository workerRepository
    ) {
        super(keysService, workerRepository);
    }
}
