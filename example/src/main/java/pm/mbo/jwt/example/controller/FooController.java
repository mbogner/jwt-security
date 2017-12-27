package pm.mbo.jwt.example.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/foo")
public class FooController {

	@RequestMapping(path = "", method = RequestMethod.GET,
		produces = MediaType.TEXT_PLAIN_VALUE)
	@ResponseStatus(HttpStatus.OK)
	@ResponseBody
	public ResponseEntity<String> get() {
		return new ResponseEntity<>("bla", HttpStatus.OK);
	}

}
