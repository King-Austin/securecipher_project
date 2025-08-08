import { useState, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ChevronRight, ChevronLeft, Shield, AlertCircle, Loader2 } from 'lucide-react';
import { secureRequest } from '../services/secureApi';

const steps = ['Personal Information', 'Verification', 'Account Security'];

export default function Registration() {
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    email: '',
    username: '',
    pin: '',
    confirm_pin: '',
    phone: '',
    bvn: '',
    nin: '',
    date_of_birth: '',
    address: '',
    occupation: '',
    accept_terms: false,
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionError, setSubmissionError] = useState('');
  const [success, setSuccess] = useState(false);

  const navigate = useNavigate();
  const firstErrorRef = useRef(null);

  // Autofocus first field of each step
  const stepFieldRefs = [useRef(), useRef(), useRef()];

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
    if (errors[name]) setErrors(prev => ({ ...prev, [name]: null }));
  };

  const validateAllData = () => {
    const allErrors = {};
    // Personal Information
    if (!formData.first_name.trim()) allErrors.first_name = 'First name is required';
    if (!formData.last_name.trim()) allErrors.last_name = 'Last name is required';
    if (!formData.email.trim()) {
      allErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      allErrors.email = 'Email is invalid';
    }
    if (!formData.phone.trim()) allErrors.phone = 'Phone number is required';
    // Verification
    if (!formData.bvn.trim()) {
      allErrors.bvn = 'BVN is required';
    } else if (!/^\d{11}$/.test(formData.bvn)) {
      allErrors.bvn = 'BVN must be 11 digits';
    }
    if (!formData.nin.trim()) {
      allErrors.nin = 'NIN is required';
    } else if (!/^\d{11}$/.test(formData.nin)) {
      allErrors.nin = 'NIN must be 11 digits';
    }
    if (!formData.date_of_birth) allErrors.date_of_birth = 'Date of birth is required';
    if (!formData.address.trim()) allErrors.address = 'Address is required';
    if (!formData.occupation.trim()) allErrors.occupation = 'Occupation is required';
    // Account Security (PIN)
    if (!formData.username.trim()) allErrors.username = 'Username is required';
    if (!formData.pin) {
      allErrors.pin = 'A 6-digit PIN is required';
    } else if (!/^\d{6}$/.test(formData.pin)) {
      allErrors.pin = 'PIN must be exactly 6 digits';
    }
    if (formData.pin !== formData.confirm_pin) allErrors.confirm_pin = 'PINs do not match';
    // Terms
    if (!formData.accept_terms) allErrors.accept_terms = 'You must accept the terms and privacy policy';

    setErrors(allErrors);

    // Scroll to first error
    if (Object.keys(allErrors).length > 0) {
      setTimeout(() => {
        if (firstErrorRef.current) {
          firstErrorRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 100);
    }

    return Object.keys(allErrors).length === 0;
  };

  const handleNext = () => {
    setCurrentStep(prev => Math.min(prev + 1, steps.length - 1));
    setTimeout(() => {
      if (stepFieldRefs[currentStep + 1]?.current) {
        stepFieldRefs[currentStep + 1].current.focus();
      }
    }, 100);
  };

  const handleBack = () => {
    setCurrentStep(prev => Math.max(prev - 1, 0));
    setTimeout(() => {
      if (stepFieldRefs[currentStep - 1]?.current) {
        stepFieldRefs[currentStep - 1].current.focus();
      }
    }, 100);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateAllData()) {
      setSubmissionError("Please correct the errors before submitting.");
      return;
    }
    setIsSubmitting(true);
    setSubmissionError('');
    try {
      const registrationPayload = {
        email: formData.email,
        first_name: formData.first_name,
        last_name: formData.last_name,
        phone_number: formData.phone,
        date_of_birth: formData.date_of_birth,
        address: formData.address,
        occupation: formData.occupation,
        nin: formData.nin,
        bvn: formData.bvn,
        username: formData.username,
      };
      console.log('Registration Payload:', registrationPayload);
      // Unified secure request
      const response = await secureRequest({
        target: 'register',
        payload: registrationPayload,
        pin: formData.pin
      });
      if (response && response.user) {
        localStorage.setItem('userProfile', JSON.stringify(response.user));
        localStorage.setItem('userAccounts', JSON.stringify(response.accounts || []));
        localStorage.setItem('userTransactions', JSON.stringify(response.transactions || []));
        setSuccess(true);
        setTimeout(() => {
          navigate('/dashboard', { replace: true });
        }, 1500);
      }
    } catch (err) {
      setSubmissionError(err.message || 'An unexpected error occurred. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderStep = () => {
    switch (currentStep) {
      case 0:
        return <Step1 formData={formData} handleChange={handleChange} errors={errors} inputRef={stepFieldRefs[0]} firstErrorRef={firstErrorRef} />;
      case 1:
        return <Step2 formData={formData} handleChange={handleChange} errors={errors} inputRef={stepFieldRefs[1]} firstErrorRef={firstErrorRef} />;
      case 2:
        return <Step3 formData={formData} handleChange={handleChange} errors={errors} inputRef={stepFieldRefs[2]} firstErrorRef={firstErrorRef} />;
      default:
        return null;
    }
  };

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="bg-white rounded-xl shadow-lg p-10 max-w-md text-center">
          <Shield className="mx-auto mb-4 h-12 w-12 text-green-600" />
          <h2 className="text-2xl font-bold text-gray-800 mb-2">Account Created!</h2>
          <p className="text-green-700 mb-4">Your account has been securely created. Redirecting to dashboard...</p>
          <Loader2 className="animate-spin h-6 w-6 mx-auto text-green-500" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl w-full space-y-8 bg-white p-10 rounded-xl shadow-lg">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Create Your Secure Account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Step {currentStep + 1} of {steps.length}: {steps[currentStep]}
          </p>
        </div>

        {/* Progress Bar */}
        <div className="w-full">
          <div className="flex justify-between mb-1">
            {steps.map((step, index) => (
              <div key={step} className={`text-xs font-medium ${index <= currentStep ? 'text-green-700' : 'text-gray-400'}`}>
                {step}
              </div>
            ))}
          </div>
          <div className="bg-gray-200 rounded-full h-2.5">
            <div className="bg-green-600 h-2.5 rounded-full" style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}></div>
          </div>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit} autoComplete="off">
          {renderStep()}

          {submissionError && (
            <div ref={firstErrorRef} className="flex flex-col space-y-1 text-sm text-red-600 p-3 bg-red-50 rounded-md">
              <div className="flex items-center space-x-2">
                <AlertCircle className="h-5 w-5" />
                <span>Error</span>
              </div>
              <p>{submissionError}</p>
            </div>
          )}

          <div className="flex justify-between items-center pt-6">
            {currentStep > 0 ? (
              <button
                type="button"
                onClick={handleBack}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                <ChevronLeft className="h-5 w-5 mr-2" />
                Back
              </button>
            ) : <div />}

            {currentStep < steps.length - 1 ? (
              <button
                type="button"
                onClick={handleNext}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                Next
                <ChevronRight className="h-5 w-5 ml-2" />
              </button>
            ) : (
              <button
                type="submit"
                disabled={isSubmitting}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:bg-gray-400"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="animate-spin h-5 w-5 mr-2" />
                    Creating Account...
                  </>
                ) : (
                  <>
                    <Shield className="h-5 w-5 mr-2" />
                    Complete Registration
                  </>
                )}
              </button>
            )}
          </div>
        </form>
        <p className="mt-4 text-center text-sm text-gray-600">
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-green-600 hover:text-green-500">
            Sign In
          </Link>
        </p>
      </div>
    </div>
  );
}

// --- Child Components for Steps ---

function Step1({ formData, handleChange, errors, inputRef, firstErrorRef }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <InputField
        name="first_name"
        label="First Name"
        value={formData.first_name}
        onChange={handleChange}
        error={errors.first_name}
        inputRef={inputRef}
        firstErrorRef={firstErrorRef}
        autoFocus
      />
      <InputField
        name="last_name"
        label="Last Name"
        value={formData.last_name}
        onChange={handleChange}
        error={errors.last_name}
      />
      <InputField
        name="email"
        type="email"
        label="Email Address"
        value={formData.email}
        onChange={handleChange}
        error={errors.email}
      />
      {/* Phone Number with +234 prefix */}
      <div>
        <label htmlFor="phone" className="block text-sm font-medium text-gray-700">
          Phone Number
        </label>
        <div className="mt-1 flex rounded-md shadow-sm">
          <span className="inline-flex items-center px-3 rounded-l-md border border-r-0 border-gray-300 bg-gray-50 text-gray-500 sm:text-sm">
            +234
          </span>
          <input
            id="phone"
            name="phone"
            type="tel"
            inputMode="numeric"
            pattern="[0-9]*"
            placeholder="9123456789"
            maxLength={11}
            required
            value={formData.phone}
            onChange={handleChange}
            className={`appearance-none block w-full px-3 py-2 border ${errors.phone ? 'border-red-500' : 'border-gray-300'} rounded-r-md focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
          />
        </div>
        {errors.phone && <p className="mt-2 text-sm text-red-600">{errors.phone}</p>}
      </div>
    </div>
  );
}

function Step2({ formData, handleChange, errors, inputRef, firstErrorRef }) {
  return (
    <div className="space-y-6">
      <InputField name="bvn" label="Bank Verification Number (BVN)" value={formData.bvn} onChange={handleChange} error={errors.bvn} maxLength={11} inputRef={inputRef} firstErrorRef={firstErrorRef} autoFocus />
      <InputField name="nin" label="National Identification Number (NIN)" value={formData.nin} onChange={handleChange} error={errors.nin} maxLength={11} />
      <InputField name="date_of_birth" type="date" label="Date of Birth" value={formData.date_of_birth} onChange={handleChange} error={errors.date_of_birth} />
      <InputField name="address" label="Residential Address" value={formData.address} onChange={handleChange} error={errors.address} />
      <InputField name="occupation" label="Occupation" value={formData.occupation} onChange={handleChange} error={errors.occupation} />
    </div>
  );
}

function Step3({ formData, handleChange, errors, inputRef, firstErrorRef }) {
  return (
    <div className="space-y-6">
      <InputField name="username" label="Username" value={formData.username} onChange={handleChange} error={errors.username} inputRef={inputRef} firstErrorRef={firstErrorRef} autoFocus />
      <InputField name="pin" type="password" label="6-Digit Security PIN" placeholder="your pin e.g 328712" inputMode="numeric" pattern="[0-9]{6}" value={formData.pin} onChange={handleChange} error={errors.pin} maxLength={6} />
      <InputField name="confirm_pin" type="password" pattern="[0-9]{6}" label="Confirm PIN" value={formData.confirm_pin} onChange={handleChange} error={errors.confirm_pin} placeholder='repeat the pin' maxLength={6} />
      <div className="mt-2 p-3 bg-green-50 rounded text-green-700 text-sm">
        <strong>What is your PIN used for?</strong>
        <ul className="list-disc ml-5 mt-1">
          <li>Your PIN encrypts and protects your private key on this device.</li>
          <li>It is required to authorize secure transactions and access your account.</li>
          <li>Never share your PIN with anyone. It cannot be recovered if forgotten.</li>
        </ul>
      </div>
      <div className="mt-4 flex items-center">
        <input
          id="accept_terms"
          name="accept_terms"
          type="checkbox"
          checked={formData.accept_terms}
          onChange={handleChange}
          className="h-4 w-4 text-green-600 focus:ring-green-500 border-gray-300 rounded"
        />
        <label htmlFor="accept_terms" className="ml-2 block text-sm text-gray-700">
          I accept the <a href="/terms" className="underline text-green-700">Terms</a> and <a href="/privacy" className="underline text-green-700">Privacy Policy</a>
        </label>
        {errors.accept_terms && <span className="ml-2 text-sm text-red-600">{errors.accept_terms}</span>}
      </div>
    </div>
  );
}

function InputField({
  name,
  label,
  type = 'text',
  value,
  onChange,
  error,
  isRequired = true,
  maxLength,
  placeholder,
  inputMode,
  pattern,
  inputRef,
  firstErrorRef,
  autoFocus
}) {
  return (
    <div>
      <label htmlFor={name} className="block text-sm font-medium text-gray-700">
        {label}
      </label>
      <div className="mt-1">
        <input
          ref={inputRef}
          id={name}
          name={name}
          type={type}
          required={isRequired}
          value={value}
          onChange={onChange}
          maxLength={maxLength}
          placeholder={placeholder}
          inputMode={inputMode}
          pattern={pattern}
          autoFocus={autoFocus}
          aria-invalid={!!error}
          aria-describedby={error ? `${name}-error` : undefined}
          className={`appearance-none block w-full px-3 py-2 border ${error ? 'border-red-500' : 'border-gray-300'} rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
        />
      </div>
      {error && (
        <p id={`${name}-error`} ref={firstErrorRef} className="mt-2 text-sm text-red-600">
          {error}
        </p>
      )}
    </div>
  );
}
