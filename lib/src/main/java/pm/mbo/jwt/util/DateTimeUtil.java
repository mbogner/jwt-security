package pm.mbo.jwt.util;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public final class DateTimeUtil {

	public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

	public static String toDateString(final ZonedDateTime zonedDateTime) {
		return zonedDateTime.format(DATE_TIME_FORMATTER);
	}

	public static Date toDate(final ZonedDateTime zonedDateTime) {
		return Date.from(zonedDateTime.toInstant());
	}

	private DateTimeUtil() {
		throw new IllegalAccessError();
	}
}
