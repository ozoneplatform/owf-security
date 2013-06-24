package ozone.security.session;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.springframework.security.web.authentication.session.ConcurrentSessionControlStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;

public class OzoneConcurrentSessionControlStrategy extends ConcurrentSessionControlStrategy {

    /*
     * Comparator used to sort SessionInformations by recency
     */
    private static class SessionComparator implements Comparator<SessionInformation> {
        public int compare(SessionInformation o1, SessionInformation o2) {
            return o1.getLastRequest().compareTo(o2.getLastRequest());
        }
    }

    private SessionComparator comparator = new SessionComparator();
    private boolean exceptionIfMaximumExceeded = false;

    public OzoneConcurrentSessionControlStrategy(SessionRegistry sessionRegistry) {
        super(sessionRegistry);
    }

    /**
     * This method has been copied from ConcurrentSessionControlStrategy and modified to
     * better ensure that more that the allowed number of sessions are never valid
     * at the same time.
     *
     * @see ConcurentSessionControlStrategy.allowableSessionsExceeded
     */
    protected void allowableSessionsExceeded(List<SessionInformation> sessions, 
            int allowableSessions, SessionRegistry registry) 
            throws SessionAuthenticationException {
        if (exceptionIfMaximumExceeded || (sessions == null)) {
            throw new SessionAuthenticationException(messages.getMessage(
                    "ConcurrentSessionControlStrategy.exceededAllowed",
            new Object[] {new Integer(allowableSessions)},
                "Maximum sessions of {0} for this principal exceeded"));
        }

        //BEGIN CUSTOMIZATIONS

        //sort the session by recency, increasing
        Collections.sort(sessions, comparator);

        //note - sessions does not include the new session being authenticated
        int sessionsToExpire = sessions.size() - allowableSessions + 1;

        //remove the first sessionToExpire sessions from the sorted list
        for (int i = 0; i < sessionsToExpire; i++) {
            sessions.get(i).expireNow();
        }
    }

    public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
        this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
        super.setExceptionIfMaximumExceeded(exceptionIfMaximumExceeded);
    }
}
