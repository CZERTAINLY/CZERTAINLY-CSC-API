package com.czertainly.csc.signing;

import com.czertainly.csc.service.keys.KeysService;
import com.czertainly.csc.service.keys.SessionKey;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

@Component
public class SessionKeySelector extends LocalKeySelector<SessionKey> {


    public SessionKeySelector(KeysService<SessionKey> keysService,
                              WorkerRepository workerRepository
    ) {
        super(keysService, workerRepository);
    }
}
