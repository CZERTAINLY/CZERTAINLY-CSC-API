package com.otilm.csc.signing;

import com.otilm.csc.service.keys.KeysService;
import com.otilm.csc.service.keys.SessionKey;
import com.otilm.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

@Component
public class SessionKeySelector extends LocalKeySelector<SessionKey> {


    public SessionKeySelector(KeysService<SessionKey> keysService,
                              WorkerRepository workerRepository
    ) {
        super(keysService, workerRepository);
    }
}
