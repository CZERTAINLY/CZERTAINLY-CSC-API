package com.czertainly.csc.signing;

import com.czertainly.csc.service.keys.KeysService;
import com.czertainly.csc.service.keys.OneTimeKey;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

@Component
public class OneTimeKeySelector extends LocalKeySelector<OneTimeKey> {


    public OneTimeKeySelector(KeysService<OneTimeKey> keysService,
                              WorkerRepository workerRepository
    ) {
        super(keysService, workerRepository);
    }
}
