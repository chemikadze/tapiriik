from datetime import  timedelta

import pytz
import pyaerobia

from tapiriik.services.service_base import ServiceAuthenticationType, ServiceBase
from tapiriik.services.interchange import UploadedActivity, ActivityType
from tapiriik.services.api import APIException, APIExcludeActivity, UserException, UserExceptionType
from tapiriik.services.tcx import TCXIO
from tapiriik.services.sessioncache import SessionCache

import logging
logger = logging.getLogger(__name__)

class AerobiaService(ServiceBase):
    ID = "aerobia"
    DisplayName = "Aerobia"
    AuthenticationType = ServiceAuthenticationType.UsernamePassword
    RequiresExtendedAuthorizationDetails = False

    _activityMappings = {
        "biking": ActivityType.Cycling,
        "cycling sport": ActivityType.Cycling,
        "spinning": ActivityType.Cycling,
        "mountain bike": ActivityType.MountainBiking,

        "running": ActivityType.Running,
        "indoor running": ActivityType.Running,
        "orienteering": ActivityType.Running,

        "walking": ActivityType.Walking,
        "nordic walking": ActivityType.Walking,
        "fitness walking": ActivityType.Walking,

        "hiking": ActivityType.Hiking,

        "skiing (downhill)": ActivityType.DownhillSkiing,

        "skiing": ActivityType.CrossCountrySkiing,
        "classic skiing": ActivityType.CrossCountrySkiing,

        "roller skating": ActivityType.Skating,
        "rollerskiing": ActivityType.Skating,
        "roller sport": ActivityType.Skating,
        "skateboard": ActivityType.Skating,
        "figure skating": ActivityType.Skating,

        "swimming": ActivityType.Swimming,

        "snowboard": ActivityType.Snowboarding,

        "opa": ActivityType.Other,
        "gym": ActivityType.Other,
        "trx": ActivityType.Other,
        "other": ActivityType.Other,
        "water aerobics": ActivityType.Other,
        "acrobatics": ActivityType.Other,
        "aerobics": ActivityType.Other,
        "box": ActivityType.Other,
        "badminton": ActivityType.Other,
        "basketball": ActivityType.Other,
        "volleyball": ActivityType.Other,
        "beach volleyball": ActivityType.Other,
        "martial arts": ActivityType.Other,
        "handball": ActivityType.Other,
        "gymnastics": ActivityType.Other,
        "golf": ActivityType.Other,
        "canoeing": ActivityType.Other,
        "scuba diving": ActivityType.Other,
        "deltaplan": ActivityType.Other,
        "yoga": ActivityType.Other,
        "kiteboarding": ActivityType.Other,
        "kerling": ActivityType.Other,
        "horse riding": ActivityType.Other,
        "skating": ActivityType.Other,
        "crossfit": ActivityType.Other,
        "circle workout": ActivityType.Other,
        "motorsport": ActivityType.Other,
        "mma": ActivityType.Other,
        "paraplane": ActivityType.Other,
        "pilates": ActivityType.Other,
        "polo": ActivityType.Other,
        "stretching": ActivityType.Other,
        "rugby": ActivityType.Other,
        "fishing": ActivityType.Other,
        "scooter": ActivityType.Other,
        "windsurfing": ActivityType.Other,
        "rock climbing": ActivityType.Other,
        "squash": ActivityType.Other,
        "sport": ActivityType.Other,
        "stepper": ActivityType.Other,
        "dancing": ActivityType.Other,
        "tennis": ActivityType.Other,
        "table tennis": ActivityType.Other,
        "triathlon": ActivityType.Other,
        "outdoor fitness": ActivityType.Other,
        "football": ActivityType.Other,
        "fencing": ActivityType.Other,
        "hockey": ActivityType.Other,
        "chess": ActivityType.Other,
        "ellipse": ActivityType.Other
    }
    _activityMappings = map(lambda k, v: (''.join(k.lower().split()), v), _activityMappings.items())

    SupportedActivities = list(_activityMappings.values())

    SupportsHR = SupportsCadence = True

    _sessionCache = SessionCache(lifetime=timedelta(minutes=30), freshen_on_get=True)

    def _get_connection(self, email, password):
        aerobia = pyaerobia.Aerobia()

        try:
            aerobia.auth(email, password)
        except Exception:
            raise APIException(
                "Invalid login", block=True,
                user_exception=UserException(UserExceptionType.Authorization, intervention_required=True))

        self._sessionCache.Set(email, aerobia)

        return aerobia

    def _get_connection_for_record(self, record):
        from tapiriik.auth.credential_storage import CredentialStore

        cached = self._sessionCache.Get(record.ExternalID)
        if cached:
            return cached

        password = CredentialStore.Decrypt(record.ExtendedAuthorization["Password"])
        email = CredentialStore.Decrypt(record.ExtendedAuthorization["Email"])

        connection = self._get_connection(email, password)
        self._sessionCache.Set(record.ExternalID, connection)

        return connection


    def WebInit(self):
        aerobia = pyaerobia.Aerobia()
        self.UserAuthorizationURL = aerobia.auth_url()

    def Authorize(self, email, password, store=False):
        from tapiriik.auth.credential_storage import CredentialStore

        # check we can authorize with given credentials
        conn = self._get_connection(email, password)

        member_id = conn.user_id()

        return member_id, {}, {"Email": CredentialStore.Encrypt(email), "Password": CredentialStore.Encrypt(password)}

    def DownloadActivityList(self, serviceRecord, exhaustive=False):

        activities = []
        exclusions = [] # TODO workouts that can not be downloaded

        connection = self._get_connection_for_record(serviceRecord)

        for workout in connection.workout_iterator(serviceRecord.ExternalID):
            activity = UploadedActivity()

            activity.TZ = pytz.timezone("UTC+4") # TODO

            logger.debug("Name " + workout.name + ":")
            activity.Name = workout["name"]

            activity.StartTime = workout.date
            activity.EndTime = activity.StartTime + workout.duration
            logger.debug("Activity s/t " + str(activity.StartTime))
            activity.AdjustTZ()

            activity.Distance = float(workout.length * 1000)
            activity.Type = self._activityMappings.get(''.join(workout.type.lower().split()), ActivityType.Other)

            activity.CalculateUID()
            activity.UploadedTo = [{"Connection": serviceRecord, "ActivityID": workout.id}]
            activities.append(activity)

        return activities, exclusions

    def DownloadActivity(self, serviceRecord, activity):
        activityID = [x["ActivityID"] for x in activity.UploadedTo if x["Connection"] == serviceRecord][0]
        connection = self._get_connection_for_record(serviceRecord)
        try:
            TCXIO.Parse(connection.export_workout(activityID, fmt='tcx'), activity)
        except ValueError as e:
            raise APIExcludeActivity("TCX parse error " + str(e))

        return activity

    def UploadActivity(self, serviceRecord, activity):
        activity.EnsureTZ()
        connection = self._get_connection_for_record(serviceRecord)

        tcx_file = TCXIO.Dump(activity)
        try:
            connection.import_workout(tcx_file) # TODO: name, private/public
        except Exception as e:
            raise APIException("Unable to upload activity")

    def RevokeAuthorization(self, serviceRecord):
        # nothing to do here...
        pass

    def DeleteCachedData(self, serviceRecord):
        # nothing cached...
        pass
