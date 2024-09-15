//make a async handler function , to use as with async await as wraper

const asyncHandler = (requestHandler) => {
  return (req, res, next) => {
      Promise
      .resolve(requestHandler(req, res, next))
      .catch((error) => next(error))
  }
};

export { asyncHandler }