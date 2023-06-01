import { useState } from 'react';
import { Container, Form, Button } from 'react-bootstrap';
import axios from 'axios';
import 'bootstrap/dist/css/bootstrap.min.css';

function App() {
  const [config, setConfig] = useState('');
  const [honeypotType, setHoneypotType] = useState('dionaea');
  const [report, setReport] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/api/run', {
        config,
        honeypot_type: honeypotType,
      });
      setReport(response.data);
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <Container>
      <h1>honeyscanner: A vulnerability analyzer for honeypots</h1>
      <Form onSubmit={handleSubmit}>
        <Form.Group>
          <Form.Label>Configuration:</Form.Label>
          <Form.Control
            as="textarea"
            rows={10}
            value={config}
            onChange={(e) => setConfig(e.target.value)}
          />
        </Form.Group>
        <Form.Group>
          <Form.Label>Honeypot Type:</Form.Label>
          <Form.Control
            as="select"
            value={honeypotType}
            onChange={(e) => setHoneypotType(e.target.value)}
          >
            <option value="dionaea">Dionaea</option>
            <option value="cowrie">Cowrie</option>
            <option value="conpot">Conpot</option>
          </Form.Control>
        </Form.Group>
        <Button type="submit">Run</Button>
      </Form>
      {report && (
        <div>
          <h2>Report:</h2>
          <pre>{JSON.stringify(report, null, 2)}</pre>
        </div>
      )}
    </Container>
  );
}

export default App;